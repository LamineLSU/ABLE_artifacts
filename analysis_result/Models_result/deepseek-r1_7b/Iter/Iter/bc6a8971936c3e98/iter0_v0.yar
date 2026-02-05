rule Bypass_Evasion {
    meta:
        description = "Evasion bypass patterns targeting different points in the code"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 E8 D7 56 60 }  // TEST JZ XOR
        $pattern1 = { 5B 7D F9 E3 E3 E4 07 D0 }  // POP CALL XOR
        $pattern2 = { 5F EB 5A 01 81 36 D8 C0 }  // PUSH XOR JNZ

    condition:
        any of them
}