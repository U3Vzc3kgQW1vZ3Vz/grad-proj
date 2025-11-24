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

package pascal.taie.language.protocols;

import soot.SootClass;
import soot.SootMethod;
import soot.VoidType;

/**
 * Protocol rule for SnakeYAML (YAML parsing library for Java).
 *
 * SnakeYAML uses JavaBean conventions for classes explicitly used in YAML deserialization.
 * To reduce false positives, this is more conservative than JSON protocol.
 *
 * Entry methods that start the deserialization process in SnakeYAML:
 * - <init>(): No-arg constructors for object instantiation
 * - set*(): Setters for property writing during deserialization
 * - get*(): Collection getters (Map/Collection) that may trigger side effects
 *
 * Note: Detection is disabled by default (ENABLE_YAML_DETECTION = false) to avoid false positives.
 *
 * References:
 * - SnakeYAML Guide: https://www.baeldung.com/java-snake-yaml
 * - SnakeYAML Security: https://snyk.io/blog/snakeyaml-unsafe-deserialization-vulnerability/
 */
public class YamlProtocol implements ProtocolRule {

    // Conservative mode: only enable if you're specifically analyzing YAML deserialization
    // Set to true to detect all potential YAML-deserializable classes
    private static final boolean ENABLE_YAML_DETECTION = false;

    @Override
    public String getProtocolName() {
        return "SnakeYAML";
    }

    @Override
    public boolean isMagicMethod(SootMethod method, SootClass declaringClass) {
        // SnakeYAML detection is opt-in to avoid false positives
        if (!ENABLE_YAML_DETECTION) {
            return false;
        }

        if (!method.isConcrete() || !method.isPublic()) {
            return false;
        }

        String methodName = method.getName();

        // No-arg constructor - Entry method for object instantiation
        if (methodName.equals("<init>") && method.getParameterCount() == 0) {
            return true;
        }

        // Setter methods - Entry methods for property writing during deserialization
        if (methodName.startsWith("set") && methodName.length() > 3
                && method.getParameterCount() == 1
                && method.getReturnType().equals(VoidType.v())) {
            return true;
        }

        // Collection getter methods - Entry methods that may trigger side effects
        // Only consider getters that return Map/Collection
        if (methodName.startsWith("get") && methodName.length() > 3
                && method.getParameterCount() == 0
                && !method.getReturnType().equals(VoidType.v())) {
             String returnType = method.getReturnType().toString();
             return returnType.contains("java.util.Map") || returnType.contains("java.util.Collection");
        }

        return false;
    }

    @Override
    public boolean isApplicableToClass(SootClass sootClass) {
        // Only apply if YAML detection is enabled
        return ENABLE_YAML_DETECTION;
    }
}
