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
 * Protocol rule for Android Parcelable interface.
 *
 * Parcelable is Android's optimized serialization mechanism for
 * inter-component communication (IPC).
 *
 * Required methods:
 * - writeToParcel: Flatten object into a Parcel
 * - describeContents: Describe special objects in the parcelable
 * - CREATOR field with createFromParcel and newArray (not a method but critical)
 *
 * References:
 * - Android Parcelable: https://developer.android.com/reference/android/os/Parcelable
 * - Parcelable Guide: https://guides.codepath.com/android/using-parcelable
 */
public class AndroidParcelableProtocol implements ProtocolRule {

    /**
     * Required Parcelable methods:
     * - writeToParcel: Serialize object to Parcel
     * - describeContents: Return bitmask indicating special object types
     * - createFromParcel: Part of CREATOR, reconstructs object from Parcel
     * - newArray: Part of CREATOR, creates array of Parcelable
     */
    private static final Set<String> MAGIC_METHOD_SUBSIGS = Set.of(
            // Instance methods
            "void writeToParcel(android.os.Parcel,int)",
            "int describeContents()",
            // CREATOR methods (static in CREATOR field)
            "java.lang.Object createFromParcel(android.os.Parcel)",
            "java.lang.Object[] newArray(int)"
    );

    @Override
    public String getProtocolName() {
        return "Android Parcelable";
    }

    @Override
    public boolean isMagicMethod(SootMethod method, SootClass declaringClass) {
        return MAGIC_METHOD_SUBSIGS.contains(method.getSubSignature());
    }

    @Override
    public boolean isApplicableToClass(SootClass sootClass) {
        return sootClass.implementsInterface("android.os.Parcelable");
    }
}
