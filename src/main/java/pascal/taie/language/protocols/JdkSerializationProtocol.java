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
 * Protocol rule for JDK native serialization and related mechanisms.
 *
 * References:
 * - Java Serialization Spec: https://docs.oracle.com/en/java/javase/11/docs/specs/serialization/input.html
 * - Serialization Entry Methods: https://www.baeldung.com/java-serialization-readobject-vs-readresolve
 * - Externalizable Interface: https://docs.oracle.com/javase/8/docs/api/java/io/Externalizable.html
 */
public class JdkSerializationProtocol implements ProtocolRule {

    /**
     * Entry methods for Serializable interface:
     * - readObject: Custom deserialization logic (Entry Point)
     * - readObjectNoData: Handle class evolution when superclass is not serializable (Entry Point)
     * - readResolve: Replace deserialized object (Entry Point)
     * - validateObject: Validate object state after deserialization (Entry Point)
     *
     * Entry methods for Externalizable interface:
     * - readExternal: Complete control over deserialization (Entry Point)
     */
    private static final Set<String> ENTRY_METHOD_SUBSIGS = Set.of(
            // Serializable methods
            "void readObject(java.io.ObjectInputStream)",
            "java.lang.Object readResolve()",
            "void readObjectNoData()",
            "void validateObject()",
            // Externalizable methods
            "void readExternal(java.io.ObjectInput)"
    );

    @Override
    public String getProtocolName() {
        return "JDK Serialization";
    }

    @Override
    public boolean isMagicMethod(SootMethod method, SootClass declaringClass) {
        return ENTRY_METHOD_SUBSIGS.contains(method.getSubSignature());
    }

    @Override
    public boolean isApplicableToClass(SootClass sootClass) {
        return sootClass.implementsInterface("java.io.Serializable")
                || sootClass.implementsInterface("java.io.Externalizable");
    }
}
