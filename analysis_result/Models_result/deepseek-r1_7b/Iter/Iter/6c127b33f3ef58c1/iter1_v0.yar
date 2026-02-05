rule Bypass_Samples {
    meta:
        description: "Evasion bypass targeting key instructions"
        cape_options: "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 F7 25 00 8B 40 ?? }  // Around the E8F72500h call with offset
        $pattern1 = { 83 F8 01 74 20 }          // The comparison instruction and its jump (je)
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? } // Another distinct code flow point

    condition:
        any_ofthem
}