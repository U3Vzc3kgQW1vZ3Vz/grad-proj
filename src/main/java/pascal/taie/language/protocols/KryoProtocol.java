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
 * - KryoSerializable interface with write() and read() methods
 * - No-arg constructors for object instantiation
 *
 * References:
 * - Kryo Documentation: https://github.com/EsotericSoftware/kryo
 * - Kryo Tutorial: https://www.baeldung.com/kryo
 */
public class KryoProtocol implements ProtocolRule {

    /**
     * Magic methods for KryoSerializable interface:
     * - write: Custom serialization to Output stream
     * - read: Custom deserialization from Input stream
     */
    private static final Set<String> MAGIC_METHOD_SUBSIGS = Set.of(
            // KryoSerializable interface methods
            "void write(com.esotericsoftware.kryo.Kryo,com.esotericsoftware.kryo.io.Output)",
            "void read(com.esotericsoftware.kryo.Kryo,com.esotericsoftware.kryo.io.Input)",
            // No-arg constructor used for instantiation
            "void <init>()"
    );

    @Override
    public String getProtocolName() {
        return "Kryo";
    }

    @Override
    public boolean isMagicMethod(SootMethod method, SootClass declaringClass) {
        return MAGIC_METHOD_SUBSIGS.contains(method.getSubSignature());
    }

    @Override
    public boolean isApplicableToClass(SootClass sootClass) {
        return sootClass.implementsInterface("com.esotericsoftware.kryo.KryoSerializable")
                || true; // Kryo can serialize any class with no-arg constructor
    }
}
