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
 * Protocol rule for Hessian binary web services protocol.
 *
 * Hessian triggers Map.put() during HashMap deserialization and also
 * respects Java serialization magic methods (readResolve, writeReplace).
 *
 * References:
 * - Hessian Binary Web Service Protocol: http://hessian.caucho.com/doc/hessian-serialization.html
 * - Research on Hessian gadgets: https://github.com/STMCyber/RmiTaste
 */
public class HessianProtocol implements ProtocolRule {

    /**
     * Entry methods that start the deserialization process in Hessian:
     * - readResolve: Called after object deserialization to replace the object
     * - HashMap.put: Called during HashMap deserialization (handled separately in isMagicMethod)
     */
    private static final Set<String> ENTRY_METHOD_SUBSIGS = Set.of(
            "java.lang.Object readResolve()"
    );

    @Override
    public String getProtocolName() {
        return "Hessian";
    }

    @Override
    public boolean isMagicMethod(SootMethod method, SootClass declaringClass) {
        String subSig = method.getSubSignature();

        // HashMap.put() is a deserialization entry method called by Hessian framework
        // when deserializing a HashMap. We strictly limit this to java.util.HashMap
        // to avoid false positives.
        if ("java.lang.Object put(java.lang.Object,java.lang.Object)".equals(subSig)) {
            return isHashMapOrSubclass(declaringClass);
        }

        return ENTRY_METHOD_SUBSIGS.contains(subSig);
    }

    @Override
    public boolean isApplicableToClass(SootClass sootClass) {
        // Applicable if it is HashMap (for put entry) or Serializable (for readResolve)
        return isHashMapOrSubclass(sootClass)
                || sootClass.implementsInterface("java.io.Serializable");
    }

    private boolean isHashMapOrSubclass(SootClass sootClass) {
        if (sootClass.getName().equals("java.util.HashMap")) {
            return true;
        }
        if (sootClass.hasSuperclass()) {
            if(sootClass.getSuperclass().getName().equals("java.util.HashMap")){
                System.out.println(sootClass);
            }
            
            return isHashMapOrSubclass(sootClass.getSuperclass());
        }
        return false;
    }
}
