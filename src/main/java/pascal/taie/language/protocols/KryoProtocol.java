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

import java.util.Set;

/**
 * Protocol rule for Kryo binary serialization framework.
 *
 * Kryo supports custom serialization through:
 * - KryoSerializable interface with read() method for custom deserialization
 * - No-arg constructors for object instantiation (but only for classes actually used with Kryo)
 *
 * To reduce false positives, this protocol uses conservative detection:
 * - Only detects classes that implement KryoSerializable, OR
 * - Classes that implement Serializable AND have no-arg constructor (common Kryo pattern), OR
 * - Aggressive mode is enabled
 *
 * References:
 * - Kryo Documentation: https://github.com/EsotericSoftware/kryo
 * - Kryo Tutorial: https://www.baeldung.com/kryo
 */
public class KryoProtocol implements ProtocolRule {

    // Enable to detect all classes with no-arg constructors (may have many false positives)
    private static final boolean AGGRESSIVE_MODE = false;

    /**
     * Entry methods that start the deserialization process in Kryo:
     * - read: Custom deserialization from Input stream (KryoSerializable interface)
     * - <init>(): No-arg constructor used for object instantiation during deserialization
     */
    private static final Set<String> ENTRY_METHOD_SUBSIGS = Set.of(
            // KryoSerializable deserialization entry method
            "void read(com.esotericsoftware.kryo.Kryo,com.esotericsoftware.kryo.io.Input)",
            // No-arg constructor for instantiation
            "void <init>()"
    );

    @Override
    public String getProtocolName() {
        return "Kryo";
    }

    @Override
    public boolean isMagicMethod(SootMethod method, SootClass declaringClass) {
        String subSig = method.getSubSignature();

        // Always detect KryoSerializable.read() method
        if ("void read(com.esotericsoftware.kryo.Kryo,com.esotericsoftware.kryo.io.Input)".equals(subSig)) {
            return true;
        }

        // Only detect no-arg constructors if the class is applicable for Kryo
        if ("void <init>()".equals(subSig)) {
            return AGGRESSIVE_MODE || isApplicableToClass(declaringClass);
        }

        return false;
    }

    @Override
    public boolean isApplicableToClass(SootClass sootClass) {
        // Classes that implement KryoSerializable are definitely used with Kryo
        if (sootClass.implementsInterface("com.esotericsoftware.kryo.KryoSerializable")) {
            return true;
        }

        // Conservative heuristic: Kryo is often used with Serializable classes as DTOs
        // This reduces false positives from UI components, frameworks, etc.
        if (sootClass.implementsInterface("java.io.Serializable")) {
            // Additional heuristic: exclude common UI/framework packages
            String className = sootClass.getName();
            if (isLikelyUIOrFrameworkClass(className)) {
                return false;
            }
            return true;
        }

        return AGGRESSIVE_MODE;
    }

    /**
     * Heuristic to exclude common UI components and framework classes that are
     * unlikely to be used with Kryo for serialization.
     */
    private boolean isLikelyUIOrFrameworkClass(String className) {
        // Vaadin UI components
        if (className.startsWith("com.vaadin.ui.")) {
            return true;
        }

        // Swing/AWT UI components
        if (className.startsWith("javax.swing.") || className.startsWith("java.awt.")) {
            return true;
        }

        // Android UI components
        if (className.startsWith("android.widget.") || className.startsWith("android.view.")) {
            return true;
        }

        // Spring Framework internal classes
        if (className.startsWith("org.springframework.") && !className.contains(".dto.")
                && !className.contains(".model.") && !className.contains(".entity.")) {
            return true;
        }

        return false;
    }
}
