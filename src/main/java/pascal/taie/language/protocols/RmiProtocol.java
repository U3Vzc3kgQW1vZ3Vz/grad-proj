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

/**
 * Protocol rule for Java RMI (Remote Method Invocation).
 *
 * RMI uses Java serialization for parameter marshalling and unmarshalling.
 * All remote interface methods can trigger deserialization of their parameters.
 *
 * When parameters are non-primitive types, they are deserialized using
 * readObject(), making all Remote interface methods potential entry points
 * for deserialization gadgets.
 *
 * References:
 * - RMI Attacks: https://mogwailabs.de/en/blog/2019/03/attacking-java-rmi-services-after-jep-290/
 * - RMI Security Tools: https://github.com/qtc-de/remote-method-guesser
 * - Java RMI Spec: https://docs.oracle.com/en/java/javase/14/docs/specs/rmi/objmodel.html
 */
public class RmiProtocol implements ProtocolRule {

    @Override
    public String getProtocolName() {
        return "Java RMI";
    }

    @Override
    public boolean isMagicMethod(SootMethod method, SootClass declaringClass) {
        // RMI relies on JDK serialization (readObject) for parameter unmarshalling.
        // The actual entry points for gadget chains are the readObject methods of the arguments,
        // which are already covered by JdkSerializationProtocol.
        // Marking Remote methods as magic is incorrect for gadget detection as they are
        // application endpoints, not gadget triggers.
        return false;
    }

    @Override
    public boolean isApplicableToClass(SootClass sootClass) {
        return isRemoteInterface(sootClass);
    }

    private boolean isRemoteInterface(SootClass sootClass) {
        // Check if class extends java.rmi.Remote
        if (sootClass.implementsInterface("java.rmi.Remote")) {
            return true;
        }

        // Check superclass recursively
        if (sootClass.hasSuperclass()) {
            return isRemoteInterface(sootClass.getSuperclass());
        }

        return false;
    }
}
