package pascal.taie.analysis.gadget.source;

import pascal.taie.ir.exp.Var;
import pascal.taie.language.classes.JClass;
import pascal.taie.language.classes.JField;
import pascal.taie.language.classes.JMethod;
import pascal.taie.language.type.Type;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Represents a controllable source in gadget chain analysis.
 * Adapted from jdd's SourceNode for Pascal Taie.
 *
 * A source can be:
 * - A method parameter
 * - An object field
 * - A field of a parameter
 * - A constant value
 */
public class SourceNode {

    /**
     * Source type
     */
    public enum Type {
        PARAMETER,           // Method parameter
        FIELD,              // Object field
        FIELD_OF_PARAMETER, // Field accessed from parameter
        CONSTANT            // Constant value
    }

    private final Type type;

    // For PARAMETER sources
    private Integer paramIndex;      // -1 for 'this', 0+ for actual parameters
    private JMethod entryMethod;

    // For FIELD sources
    private List<JField> fieldPath;  // Chain of field accesses
    private JClass classOfField;

    // For CONSTANT sources
    private Object constantValue;

    // Metadata
    private int classId = 0;         // For tracking in gadget chains
    private boolean checkFlag = true;

    /**
     * Create a parameter source
     */
    public SourceNode(Integer paramIndex, JMethod entryMethod) {
        this.type = Type.PARAMETER;
        this.paramIndex = paramIndex;
        this.entryMethod = entryMethod;
        this.fieldPath = new ArrayList<>();
    }

    /**
     * Create a field source
     */
    public SourceNode(List<JField> fieldPath, JClass classOfField) {
        if (fieldPath.isEmpty()) {
            throw new IllegalArgumentException("Field path cannot be empty");
        }

        this.type = Type.FIELD;
        this.fieldPath = new ArrayList<>(fieldPath);
        this.classOfField = classOfField != null ? classOfField : fieldPath.get(0).getDeclaringClass();
        this.paramIndex = null;
        this.entryMethod = null;
    }

    /**
     * Create a field-of-parameter source
     */
    public SourceNode(List<JField> fieldPath, JClass classOfField, Integer paramIndex, JMethod entryMethod) {
        if (fieldPath.isEmpty()) {
            throw new IllegalArgumentException("Field path cannot be empty");
        }

        this.type = Type.FIELD_OF_PARAMETER;
        this.fieldPath = new ArrayList<>(fieldPath);
        this.classOfField = classOfField != null ? classOfField : fieldPath.get(0).getDeclaringClass();
        this.paramIndex = paramIndex;
        this.entryMethod = entryMethod;
    }

    /**
     * Create a constant source
     */
    public SourceNode(Object constantValue) {
        this.type = Type.CONSTANT;
        this.constantValue = constantValue;
        this.fieldPath = new ArrayList<>();
    }

    /**
     * Create a field source from a single field
     */
    public static SourceNode createFieldSource(JField field, JClass declaringClass) {
        List<JField> path = new ArrayList<>();
        path.add(field);
        return new SourceNode(path, declaringClass);
    }

    // Getters

    public Type getType() {
        return type;
    }

    public boolean isParameter() {
        return type == Type.PARAMETER;
    }

    public boolean isField() {
        return type == Type.FIELD || type == Type.FIELD_OF_PARAMETER;
    }

    public boolean isFieldOfParameter() {
        return type == Type.FIELD_OF_PARAMETER;
    }

    public boolean isConstant() {
        return type == Type.CONSTANT;
    }

    public Integer getParamIndex() {
        return paramIndex;
    }

    public JMethod getEntryMethod() {
        return entryMethod;
    }

    public List<JField> getFieldPath() {
        return new ArrayList<>(fieldPath);
    }

    public JClass getClassOfField() {
        return classOfField;
    }

    public Object getConstantValue() {
        return constantValue;
    }

    public int getClassId() {
        return classId;
    }

    public void setClassId(int classId) {
        this.classId = classId;
    }

    public boolean isCheckFlag() {
        return checkFlag;
    }

    public void setCheckFlag(boolean checkFlag) {
        this.checkFlag = checkFlag;
    }

    /**
     * Get the type of the value this source represents
     */
    public pascal.taie.language.type.Type getValueType() {
        switch (type) {
            case PARAMETER:
                if (paramIndex == -1) {
                    // 'this' parameter
                    return entryMethod.getDeclaringClass().getType();
                } else {
                    return entryMethod.getParamType(paramIndex);
                }
            case FIELD:
            case FIELD_OF_PARAMETER:
                return fieldPath.get(fieldPath.size() - 1).getType();
            case CONSTANT:
                // Would need to infer type from constant value
                return null;
            default:
                return null;
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof SourceNode)) {
            return false;
        }
        SourceNode other = (SourceNode) obj;

        if (type != other.type) {
            return false;
        }

        switch (type) {
            case PARAMETER:
                return Objects.equals(paramIndex, other.paramIndex) &&
                       Objects.equals(entryMethod, other.entryMethod);
            case FIELD:
                return Objects.equals(fieldPath, other.fieldPath) &&
                       Objects.equals(classOfField, other.classOfField);
            case FIELD_OF_PARAMETER:
                return Objects.equals(fieldPath, other.fieldPath) &&
                       Objects.equals(classOfField, other.classOfField) &&
                       Objects.equals(paramIndex, other.paramIndex) &&
                       Objects.equals(entryMethod, other.entryMethod);
            case CONSTANT:
                return Objects.equals(constantValue, other.constantValue);
            default:
                return false;
        }
    }

    @Override
    public int hashCode() {
        switch (type) {
            case PARAMETER:
                return Objects.hash(type, paramIndex, entryMethod);
            case FIELD:
                return Objects.hash(type, fieldPath, classOfField);
            case FIELD_OF_PARAMETER:
                return Objects.hash(type, fieldPath, classOfField, paramIndex, entryMethod);
            case CONSTANT:
                return Objects.hash(type, constantValue);
            default:
                return 0;
        }
    }

    @Override
    public String toString() {
        switch (type) {
            case PARAMETER:
                if (paramIndex == -1) {
                    return String.format("Param[this of %s]", entryMethod.getSignature());
                } else {
                    return String.format("Param[%d of %s]", paramIndex, entryMethod.getSignature());
                }
            case FIELD:
                JField lastField = fieldPath.get(fieldPath.size() - 1);
                return String.format("Field[%s]", lastField.getSignature());
            case FIELD_OF_PARAMETER:
                JField lastFieldOfParam = fieldPath.get(fieldPath.size() - 1);
                return String.format("Field[%s of param %d]", lastFieldOfParam.getSignature(), paramIndex);
            case CONSTANT:
                return String.format("Constant[%s]", constantValue);
            default:
                return "Unknown";
        }
    }
}
