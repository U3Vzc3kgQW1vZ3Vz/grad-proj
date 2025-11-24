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

import java.util.Set;

/**
 * Protocol rule for XStream XML serialization library.
 *
 * XStream respects Java serialization magic methods and also invokes
 * JavaBean getters/setters during XML conversion.
 *
 * References:
 * - XStream User Guide: https://www.baeldung.com/xstream-serialize-object-to-xml
 * - XStream SerializableConverter: https://x-stream.github.io/javadoc/com/thoughtworks/xstream/converters/reflection/SerializableConverter.html
 */
public class XStreamProtocol implements ProtocolRule {

    /**
     * Entry methods that start the deserialization process in XStream:
     * - readObject: Custom deserialization logic (Java serialization method respected by XStream)
     * - readResolve: Object replacement after deserialization
     */
    private static final Set<String> ENTRY_METHOD_SUBSIGS = Set.of(
            "void readObject(java.io.ObjectInputStream)",
            "java.lang.Object readResolve()"
    );

    @Override
    public String getProtocolName() {
        return "XStream XML";
    }

    @Override
    public boolean isMagicMethod(SootMethod method, SootClass declaringClass) {
        // Check serialization methods
        if (ENTRY_METHOD_SUBSIGS.contains(method.getSubSignature())) {
            return true;
        }

        return false;
    }

    @Override
    public boolean isApplicableToClass(SootClass sootClass) {
        // XStream gadgets almost exclusively rely on Serializable classes
        return sootClass.implementsInterface("java.io.Serializable");
    }
}
