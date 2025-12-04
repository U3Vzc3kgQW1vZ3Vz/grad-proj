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
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with Tai-e. If not, see <https://www.gnu.org/licenses/>.
 */

package pascal.taie.language.protocols;

import soot.BooleanType;
import soot.SootClass;
import soot.SootField;
import soot.SootMethod;
import soot.VoidType;
import soot.tagkit.AnnotationTag;
import soot.tagkit.Host;
import soot.tagkit.Tag;
import soot.tagkit.VisibilityAnnotationTag;

import java.util.HashSet;
import java.util.Set;

/**
 * Protocol rule for JSON serialization frameworks (Jackson, Gson, Fastjson).
 *
 * Entry methods that start the deserialization process in JSON frameworks:
 * - &lt;init&gt;(): Constructors (annotated with @JsonCreator or no-arg default)
 * - set*(): Setter methods for property writing during deserialization
 * - get*()/is*(): Collection getters (Map/List/Set/Collection) that may trigger side effects
 * - Static factory methods: valueOf, of, from, parse, etc. (annotated or matching naming patterns)
 *
 * To reduce false positives, methods are only considered entry methods if:
 * 1. The class has JSON-related annotations, OR
 * 2. The method has JSON-related annotations, OR
 * 3. A corresponding field has JSON-related annotations, OR
 * 4. Aggressive mode is enabled (checks all public getters/setters)
 *
 * References:
 * - Jackson Annotations: https://www.baeldung.com/jackson-annotations
 * - Fastjson2 Annotations: https://github.com/alibaba/fastjson2/wiki/fastjson2_annotations
 */
public class JsonProtocol implements ProtocolRule {

    // Enable aggressive mode to check all public getters/setters (may have false positives)
    private static final boolean AGGRESSIVE_MODE = false;

    // Jackson class-level annotations (expanded)
    private static final Set<String> JACKSON_CLASS_ANNOTATIONS = Set.of(
            "com.fasterxml.jackson.annotation.JsonAutoDetect",
            "com.fasterxml.jackson.annotation.JsonDeserialize",
            "com.fasterxml.jackson.annotation.JsonSerialize",
            "com.fasterxml.jackson.annotation.JsonTypeInfo",
            "com.fasterxml.jackson.annotation.JsonTypeName",
            "com.fasterxml.jackson.annotation.JsonIgnoreProperties",
            "com.fasterxml.jackson.annotation.JsonPropertyOrder",
            "com.fasterxml.jackson.annotation.JsonRootName",
            "com.fasterxml.jackson.annotation.JsonFilter",
            "com.fasterxml.jackson.annotation.JsonIdentityInfo",
            "com.fasterxml.jackson.annotation.JsonSubTypes",
            "com.fasterxml.jackson.annotation.JsonInclude",
            "com.fasterxml.jackson.annotation.JsonIncludeProperties",
            "com.fasterxml.jackson.annotation.JsonIgnoreType",
            "com.fasterxml.jackson.databind.annotation.JsonDeserialize",
            "com.fasterxml.jackson.databind.annotation.JsonSerialize"
    );


    // Fastjson class-level annotations
    private static final Set<String> FASTJSON_CLASS_ANNOTATIONS = Set.of(
            "com.alibaba.fastjson.annotation.JSONType",
            "com.alibaba.fastjson2.annotation.JSONType"
    );

    // Gson class-level annotations (new)
    private static final Set<String> GSON_CLASS_ANNOTATIONS = Set.of(
            "com.google.gson.annotations.JsonAdapter"
    );

    // Combined class annotations
    private static final Set<String> CLASS_ANNOTATIONS;
    static {
        Set<String> combined = new HashSet<>(JACKSON_CLASS_ANNOTATIONS);
        combined.addAll(FASTJSON_CLASS_ANNOTATIONS);
        combined.addAll(GSON_CLASS_ANNOTATIONS);
        CLASS_ANNOTATIONS = Set.copyOf(combined);
    }

    // Method-level annotations (Jackson, Fastjson, Gson - expanded)
    private static final Set<String> JSON_METHOD_ANNOTATIONS = Set.of(
            // Jackson
            "com.fasterxml.jackson.annotation.JsonCreator",
            "com.fasterxml.jackson.annotation.JsonProperty",
            "com.fasterxml.jackson.annotation.JsonGetter",
            "com.fasterxml.jackson.annotation.JsonSetter",
            "com.fasterxml.jackson.annotation.JsonValue",
            "com.fasterxml.jackson.annotation.JsonAnyGetter",
            "com.fasterxml.jackson.annotation.JsonAnySetter",
            // Fastjson
            "com.alibaba.fastjson.annotation.JSONField",
            "com.alibaba.fastjson2.annotation.JSONField",
            // Gson (new)
            "com.google.gson.annotations.SerializedName",
            "com.google.gson.annotations.Expose",
            "com.google.gson.annotations.JsonAdapter"
    );

    // Field-level annotations (new: Jackson, Fastjson, Gson)
    private static final Set<String> JSON_FIELD_ANNOTATIONS = Set.of(
            // Jackson
            "com.fasterxml.jackson.annotation.JsonProperty",
            "com.fasterxml.jackson.annotation.JsonIgnore",
            "com.fasterxml.jackson.annotation.JsonFormat",
            "com.fasterxml.jackson.annotation.JsonUnwrapped",
            "com.fasterxml.jackson.annotation.JsonView",
            "com.fasterxml.jackson.annotation.JsonInclude",
            "com.fasterxml.jackson.annotation.JsonDeserialize",
            "com.fasterxml.jackson.annotation.JsonSerialize",
            // Fastjson
            "com.alibaba.fastjson.annotation.JSONField",
            "com.alibaba.fastjson2.annotation.JSONField",
            // Gson
            "com.google.gson.annotations.SerializedName",
            "com.google.gson.annotations.Expose"
    );

    // Ignore annotations (expanded)
    private static final Set<String> IGNORE_ANNOTATIONS = Set.of(
            "com.fasterxml.jackson.annotation.JsonIgnore",
            "com.fasterxml.jackson.annotation.JsonIgnoreProperties",
            "com.fasterxml.jackson.annotation.JsonIgnoreType"
            // Note: For Gson @Expose(expose=false), but since we can't check elements easily, treat presence as potential ignore if needed; simplified here.
    );

    @Override
    public String getProtocolName() {
        return "JSON";
    }

    @Override
    public boolean isMagicMethod(SootMethod method, SootClass declaringClass) {
        // Check ignore annotations on method
        if (hasIgnoreAnnotation(method)) {
            return false;
        }

        // Check if method has JSON annotations
        if (hasJsonAnnotation(method)) {
            return true;
        }

        // NEW: Check if method corresponds to a field with JSON annotations
        String propertyName = getPropertyNameFromMethod(method.getName());
        if (propertyName != null) {
            SootField field = declaringClass.getFieldByNameUnsafe(propertyName);
            if (field != null && (hasJsonAnnotation(field) || hasIgnoreAnnotation(field))) {
                // If field ignored, skip; else consider magic if annotated
                if (hasIgnoreAnnotation(field)) {
                    return false;
                }
                return true;
            }
        }

        // Only detect JavaBean-style methods (setters/getters/constructors) if:
        // 1. The class actually has JSON annotations (indicating it's used with JSON frameworks), OR
        // 2. Aggressive mode is enabled
        // This prevents false positives from arbitrary UI components, domain objects, etc.
        if (!AGGRESSIVE_MODE && !hasJsonAnnotation(declaringClass)) {
            return false;
        }

        if (!method.isConcrete() || !method.isPublic()) {
            return false;
        }

        String methodName = method.getName();

        // Setter methods - Entry methods for property writing during deserialization
        if (isSetterMethod(method, methodName)) {
            return true;
        }

        // Collection getter methods - Entry methods that may trigger side effects during deserialization
        if (isGetterMethod(method, methodName)) {
            return true;
        }

        // Static factory methods - Entry methods for object creation (common in Jackson @JsonCreator)
        if (isStaticFactoryMethod(method, methodName)) {
            return true;
        }

        // Constructors - Entry methods for object instantiation (default no-arg)
        if (methodName.equals("<init>") && method.getParameterCount() == 0) {
            return true;
        }

        return false;
    }

    @Override
    public boolean isApplicableToClass(SootClass sootClass) {
        // Apply to classes with JSON annotations on class, methods, or fields (NEW: added field checks), or all in aggressive mode
        return AGGRESSIVE_MODE || hasJsonAnnotation(sootClass) || hasJsonAnnotatedFields(sootClass) || hasJsonAnnotatedMethods(sootClass);
    }

    /**
     * Check if a class has JSON-related annotations
     */
    private boolean hasJsonAnnotation(SootClass sootClass) {
        for (Tag tag : sootClass.getTags()) {
            if (tag instanceof VisibilityAnnotationTag) {
                VisibilityAnnotationTag vat = (VisibilityAnnotationTag) tag;
                for (AnnotationTag annotation : vat.getAnnotations()) {
                    String type = normalizeAnnotationType(annotation.getType());
                    if (CLASS_ANNOTATIONS.contains(type)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * NEW: Check if a class has any fields with JSON-related annotations
     */
    private boolean hasJsonAnnotatedFields(SootClass sootClass) {
        for (SootField field : sootClass.getFields()) {
            if (hasJsonAnnotation(field)) {
                return true;
            }
        }
        return false;
    }

    /**
     * NEW: Check if a class has any methods with JSON-related annotations
     */
    private boolean hasJsonAnnotatedMethods(SootClass sootClass) {
        for (SootMethod method : sootClass.getMethods()) {
            if (hasJsonAnnotation(method)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if a method or field has JSON-related annotations
     */
    private boolean hasJsonAnnotation(Host container) {
        Set<String> annotations = (container instanceof SootMethod) ? JSON_METHOD_ANNOTATIONS : JSON_FIELD_ANNOTATIONS;
        for (Tag tag : container.getTags()) {
            if (tag instanceof VisibilityAnnotationTag) {
                VisibilityAnnotationTag vat = (VisibilityAnnotationTag) tag;
                for (AnnotationTag annotation : vat.getAnnotations()) {
                    String type = normalizeAnnotationType(annotation.getType());
                    if (annotations.contains(type)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Check if a method or field has Ignore annotations
     */
    private boolean hasIgnoreAnnotation(Host container) {
        for (Tag tag : container.getTags()) {
            if (tag instanceof VisibilityAnnotationTag) {
                VisibilityAnnotationTag vat = (VisibilityAnnotationTag) tag;
                for (AnnotationTag annotation : vat.getAnnotations()) {
                    String type = normalizeAnnotationType(annotation.getType());
                    if (IGNORE_ANNOTATIONS.contains(type)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private String normalizeAnnotationType(String type) {
        return type.replace("L", "").replace(";", "").replace("/", ".");
    }

    private boolean isGetterMethod(SootMethod method, String methodName) {
        boolean isStandardGetter = methodName.startsWith("get")
                && methodName.length() > 3
                && method.getParameterCount() == 0
                && !method.getReturnType().equals(VoidType.v());

        boolean isBooleanGetter = methodName.startsWith("is")
                && methodName.length() > 2
                && method.getParameterCount() == 0
                && method.getReturnType() instanceof BooleanType;

        if (!isStandardGetter && !isBooleanGetter) {
            return false;
        }

        // Only consider collection getters as entry methods (may trigger side effects during deserialization)
        String returnType = method.getReturnType().toString();
        return returnType.contains("java.util.Map") ||
                returnType.contains("java.util.List") ||
                returnType.contains("java.util.Set") ||
                returnType.contains("java.util.Collection");
    }

    private boolean isSetterMethod(SootMethod method, String methodName) {
        return methodName.startsWith("set")
                && methodName.length() > 3
                && method.getParameterCount() == 1
                && method.getReturnType().equals(VoidType.v());
    }

    private boolean isStaticFactoryMethod(SootMethod method, String methodName) {
        if (!method.isStatic()) {
            return false;
        }

        // Strict check: Factory method should return an instance of the declaring class
        if (!method.getReturnType().equals(method.getDeclaringClass().getType())) {
            return false;
        }

        // Expanded common factory method names (NEW: added more like fromString, create, instance)
        if (methodName.equals("valueOf") || methodName.equals("of")
                || methodName.equals("from") || methodName.equals("fromString")
                || methodName.equals("parse") || methodName.equals("getInstance")
                || methodName.equals("newInstance") || methodName.equals("creator")
                || methodName.equals("build") || methodName.equals("create")
                || methodName.equals("instance")) {
            return true;
        }

        // Fastjson-style: static method with String parameter
        return method.getParameterCount() == 1
                && method.getParameterType(0).toString().equals("java.lang.String");
    }

    /**
     * NEW: Extract property name from getter/setter method name (e.g., getFoo -> foo)
     */
    private String getPropertyNameFromMethod(String methodName) {
        if (methodName.startsWith("get") && methodName.length() > 3) {
            return Character.toLowerCase(methodName.charAt(3)) + methodName.substring(4);
        } else if (methodName.startsWith("set") && methodName.length() > 3) {
            return Character.toLowerCase(methodName.charAt(3)) + methodName.substring(4);
        } else if (methodName.startsWith("is") && methodName.length() > 2) {
            return Character.toLowerCase(methodName.charAt(2)) + methodName.substring(3);
        }
        return null;
    }
}
