/*
 * Tai-e: A Static Analysis Framework for Java
 *
 * Copyright (C) 2022 Tian Tan <tiantan@nju.edu.cn>
 * Copyright (C) 2022 Yue Li <yueli@nju.edu.cn>
 *
 * This file is part of Tai-e.
 *
 * Tai-e is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * Tai-e is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with Tai-e. If not, see <https://www.gnu.org/licenses/>.
 */

package pascal.taie;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import pascal.taie.analysis.AnalysisManager;
import pascal.taie.analysis.dataflow.analysis.methodsummary.plugin.PrioriKnowConfig;
import pascal.taie.config.AnalysisConfig;
import pascal.taie.config.AnalysisPlanner;
import pascal.taie.config.ConfigManager;
import pascal.taie.config.Configs;
import pascal.taie.config.LoggerConfigs;
import pascal.taie.config.Options;
import pascal.taie.config.Plan;
import pascal.taie.config.PlanConfig;
import pascal.taie.config.Scope;
import pascal.taie.frontend.cache.CachedWorldBuilder;
import pascal.taie.frontend.soot.SootClassLoader;
import pascal.taie.language.classes.ClassHierarchy;
import pascal.taie.language.classes.JClass;
import pascal.taie.util.Timer;
import pascal.taie.util.collection.Lists;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

public class Main {

    private static final Logger logger = LogManager.getLogger(Main.class);

    public static void main(String... args) {
        Timer.runAndCount(() -> {
            Options options = processArgs(args);
            LoggerConfigs.setOutput(options.getOutputDir());
            Plan plan = processConfigs(options);
            if (plan.analyses().isEmpty()) {
                logger.info("No analyses are specified");
                System.exit(0);
            }
            buildWorld(options, plan.analyses());
            executePlan(plan);
            LoggerConfigs.reconfigure();
        }, "GeeCee");
    }

    /**
     * If the given options is empty or specify to print help information,
     * then print help and exit immediately.
     */
    private static Options processArgs(String... args) {
        Options options = Options.parse(args);
        if (options.isPrintHelp() || args.length == 0) {
            options.printHelp();
            System.exit(0);
        }
        return options;
    }

    private static Plan processConfigs(Options options) {
        InputStream content = Configs.getAnalysisConfig();
        List<AnalysisConfig> analysisConfigs = AnalysisConfig.parseConfigs(content);
        ConfigManager manager = new ConfigManager(analysisConfigs);
        AnalysisPlanner planner = new AnalysisPlanner(
                manager, options.getKeepResult());
        boolean reachableScope = options.getScope().equals(Scope.REACHABLE);
        if (!options.getAnalyses().isEmpty()) {
            // Analyses are specified by options
            List<PlanConfig> planConfigs = PlanConfig.readConfigs(options);
            manager.overwriteOptions(planConfigs);
            Plan plan = planner.expandPlan(
                    planConfigs, reachableScope);
            // Output analysis plan to file.
            // For outputting purpose, we first convert AnalysisConfigs
            // in the expanded plan to PlanConfigs
            planConfigs = Lists.map(plan.analyses(),
                    ac -> new PlanConfig(ac.getId(), ac.getOptions()));
            // TODO: turn off output in testing?
//            PlanConfig.writeConfigs(planConfigs, options.getOutputDir());
            if (!options.isOnlyGenPlan()) {
                // This run not only generates plan file but also executes it
                return plan;
            }
        } else if (options.getPlanFile() != null) {
            // Analyses are specified by file
            List<PlanConfig> planConfigs = PlanConfig.readConfigs(options.getPlanFile());
            manager.overwriteOptions(planConfigs);
            return planner.makePlan(planConfigs, reachableScope);
        }
        // No analyses are specified
        return Plan.emptyPlan();
    }

    /**
     * Convenient method for building the world from String arguments.
     */
    public static void buildWorld(String... args) {
        Options options = Options.parse(args);
        LoggerConfigs.setOutput(options.getOutputDir());
        Plan plan = processConfigs(options);
        buildWorld(options, plan.analyses());
        LoggerConfigs.reconfigure();
    }

    private static void buildWorld(Options options, List<AnalysisConfig> analyses) {
        Timer.runAndCount(() -> {
            try {
                Class<? extends WorldBuilder> builderClass = options.getWorldBuilderClass();
                Constructor<? extends WorldBuilder> builderCtor = builderClass.getConstructor();
                WorldBuilder builder = builderCtor.newInstance();
                if (options.isWorldCacheMode()) {
                    builder = new CachedWorldBuilder(builder);
                }
                builder.build(options, analyses);
                logger.info("{} classes with {} methods in the world",
                        World.get()
                                .getClassHierarchy()
                                .allClasses()
                                .count(),
                        World.get()
                                .allMethods()
                                .count());
                serializeClassHierarchy(options);
                setSerializable(options.getSources());
                setPD();
            } catch (InstantiationException | IllegalAccessException |
                    NoSuchMethodException | InvocationTargetException e) {
                System.err.println("Failed to build world due to " + e);
                System.exit(1);
            }
        }, "WorldBuilder");
    }

    private static void serializeClassHierarchy(Options options) {
        Timer.runAndCount(() -> {
            ClassHierarchy hierarchy = World.get().getClassHierarchy();
            Map<String, HierarchyNode> allNodes = new java.util.HashMap<>();

            // 1. Create nodes for all classes
            for (JClass jClass : (Iterable<JClass>) () -> hierarchy.allClasses().iterator()) {
                String moduleName = jClass.getModuleName();
                if (moduleName == null) {
                    moduleName = "UNKNOWN_MODULE";
                }
                allNodes.put(jClass.getName(), new HierarchyNode(moduleName));
            }

            // 2. Link children to their parents and collect all non-root nodes
            Set<String> nonRoots = new HashSet<>();
            for (JClass jClass : (Iterable<JClass>) () -> hierarchy.allClasses().iterator()) {
                HierarchyNode childNode = allNodes.get(jClass.getName());

                JClass superclass = jClass.getSuperClass();
                if (superclass != null) {
                    HierarchyNode parentNode = allNodes.get(superclass.getName());
                    if (parentNode != null) {
                        parentNode.children.put(jClass.getName(), childNode);
                        nonRoots.add(jClass.getName());
                    }
                }

                for (JClass iface : jClass.getInterfaces()) {
                    HierarchyNode parentNode = allNodes.get(iface.getName());
                    if (parentNode != null) {
                        parentNode.children.put(jClass.getName(), childNode);
                        nonRoots.add(jClass.getName());
                    }
                }
            }

            // 3. Roots are all nodes that are not in the nonRoots set; group them by module
            Map<String, Map<String, HierarchyNode>> moduleRoots = new java.util.TreeMap<>();
            for (Map.Entry<String, HierarchyNode> entry : allNodes.entrySet()) {
                if (!nonRoots.contains(entry.getKey())) {
                    HierarchyNode rootNode = entry.getValue();
                    moduleRoots
                            .computeIfAbsent(rootNode.module, k -> new java.util.TreeMap<>())
                            .put(entry.getKey(), rootNode);
                }
            }

            // Determine filename
            String identifier = PrioriKnowConfig.getIndentiferOfJar(options);
            List<String> appClassPath = options.getAppClassPath();
            String filename = String.format("class-hierarchy-%s.json", identifier);

            // Serialize using Gson
            try (java.io.Writer writer = new java.io.FileWriter(
                    new java.io.File(options.getOutputDir(), filename))) {
                Gson gson = new GsonBuilder().setPrettyPrinting().create();
                writer.write(gson.toJson(moduleRoots));
            } catch (java.io.IOException e) {
                logger.error("Failed to serialize class hierarchy", e);
            }
        }, "SerializeClassHierarchy");
    }

    private static void setPD() {
        ClassHierarchy hierarchy = World.get().getClassHierarchy();
        JClass pd = hierarchy.getClass("java.beans.PropertyDescriptor");
        for (JClass sub : hierarchy.getAllSubclassesOf(pd)) {
            if (sub.equals(pd)) continue;
            sub.getDeclaredMethods().forEach(method -> {
                String name = method.getName();
                if (name.contains("get")) {
                    if (name.contains("ReadMethod")) {
                        method.setImitatedBehavior("jump", "get");
                        method.setImitatedBehavior("fromIdx", "-1");
                    } else if (name.contains("WriteMethod")) {
                        method.setImitatedBehavior("jump", "set");
                        method.setImitatedBehavior("fromIdx", "-1");
                    }
                }
            });
        }
    }

    private static void setSerializable(List<String> sources) {
        World.get().getClassHierarchy().allClasses()
                .forEach(c -> {
                    setSerializable(c, sources);
                });
    }

    private static void setSerializable(JClass c, List<String> sources) {
        boolean flag = false;
        for (JClass sub : World.get().getClassHierarchy().getAllSubclassesOf(c)) {
            if (sub.implementSer()) {
                c.setSerializable();
                flag = true;
                break;
            }
        }
        Set<JClass> sups = new HashSet<>();
        getAllSuperclassesOf(c, sups);
        for (JClass sup : sups) {
            if (sup.implementSer()) {
                c.setSerializable();
                flag = true;
                break;
            }
        }
        if (sources.contains("serializable") && flag) {
            c.getDeclaredMethods()
                    .stream()
                    .filter(m -> SootClassLoader.readSubSigList.contains(m.getSubsignature().toString()))
                    .forEach(m -> World.get().addGCEntry(m));
        }
    }

    private static void getAllSuperclassesOf(JClass c, Set<JClass> ret) {
        JClass superClz = c.getSuperClass();
        if (superClz != null) {
            ret.add(superClz);
        }
        c.getInterfaces().forEach(i -> ret.add(i));
    }

    private static void executePlan(Plan plan) {
        new AnalysisManager(plan).execute();
    }

    /**
     * Represents a node in the class hierarchy tree for serialization.
     */
    private static class HierarchyNode {
        public final String module;
        public final Map<String, HierarchyNode> children = new java.util.TreeMap<>();

        public HierarchyNode(String module) {
            this.module = module;
        }
    }
}
