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

import java.util.ArrayList;
import java.util.List;

/**
 * Manages protocol rules for detecting magic methods across different
 * serialization/deserialization protocols.
 */
public class ProtocolManager {

    private final List<ProtocolRule> protocolRules;

    public ProtocolManager() {
        this.protocolRules = new ArrayList<>();
        registerDefaultProtocols();
    }

    private void registerDefaultProtocols() {
        // ONLY register protocols with strict checks or opt-in behavior
        // to avoid false positives

        // JDK standard serialization - ALWAYS ACTIVE (strict: requires Serializable/Externalizable)
        protocolRules.add(new JdkSerializationProtocol());

        // Hessian - ALWAYS ACTIVE (strict: requires Map interface + specific methods)
        protocolRules.add(new HessianProtocol());

        // Kryo - ALWAYS ACTIVE (strict: requires KryoSerializable or specific methods)
        protocolRules.add(new KryoProtocol());

        // JSON - ANNOTATION-BASED (only detects classes with JSON annotations by default)
        protocolRules.add(new JsonProtocol());

        // RMI - ALWAYS ACTIVE (strict: requires Remote interface)
        protocolRules.add(new RmiProtocol());

        // Android Parcelable - ALWAYS ACTIVE (strict: requires Parcelable interface)
        protocolRules.add(new AndroidParcelableProtocol());

        // XStream - DISABLED BY DEFAULT (too broad - detects all getters/setters)
        // To enable: manually register with protocolManager.registerProtocol(new XStreamProtocol())
        // protocolRules.add(new XStreamProtocol());

        // SnakeYAML - DISABLED BY DEFAULT (too broad - detects all JavaBeans)
        // Already disabled in YamlProtocol.java with ENABLE_YAML_DETECTION = false
        protocolRules.add(new YamlProtocol());
    }

    public void registerProtocol(ProtocolRule rule) {
        protocolRules.add(rule);
    }

    /**
     * Checks if a method is a magic method according to any registered protocol.
     * @param method the method to check
     * @param declaringClass the class declaring the method
     * @return true if the method is identified as a magic method by any protocol
     */
    public boolean isMagicMethod(SootMethod method, SootClass declaringClass) {
        for (ProtocolRule rule : protocolRules) {
            if (rule.isApplicableToClass(declaringClass)
                    && rule.isMagicMethod(method, declaringClass)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Gets the protocol that identifies this method as a magic method.
     * @param method the method to check
     * @param declaringClass the class declaring the method
     * @return the protocol name, or null if not a magic method
     */
    public String getMatchingProtocol(SootMethod method, SootClass declaringClass) {
        for (ProtocolRule rule : protocolRules) {
            if (rule.isApplicableToClass(declaringClass)
                    && rule.isMagicMethod(method, declaringClass)) {
                return rule.getProtocolName();
            }
        }
        return null;
    }

    public List<ProtocolRule> getProtocolRules() {
        return new ArrayList<>(protocolRules);
    }
}
