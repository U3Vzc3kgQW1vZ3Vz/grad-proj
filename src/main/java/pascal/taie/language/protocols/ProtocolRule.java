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
 * Interface for protocol-specific magic method detection rules.
 * Each protocol (JDK serialization, Hessian, JSON, etc.) defines
 * its own magic methods that serve as entry points for gadget chains.
 */
public interface ProtocolRule {

    /**
     * Gets the name of this protocol.
     * @return protocol name (e.g., "JDK", "Hessian", "JSON")
     */
    String getProtocolName();

    /**
     * Checks if a method is a magic method (source/entry point) for this protocol.
     * @param method the method to check
     * @param declaringClass the class declaring the method
     * @return true if the method is a magic method for this protocol
     */
    boolean isMagicMethod(SootMethod method, SootClass declaringClass);

    /**
     * Checks if this protocol requires the class to implement specific interfaces.
     * @param sootClass the class to check
     * @return true if the class satisfies protocol requirements
     */
    default boolean isApplicableToClass(SootClass sootClass) {
        return true;
    }
}
