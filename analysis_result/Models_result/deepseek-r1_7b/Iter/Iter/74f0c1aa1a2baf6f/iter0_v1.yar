rule Bypass_Evasion {
    meta:
        description = "Evasion bypass using TEST and conditional jump instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 FF 45 6A 5F }  // TEST EAX followed by JZ
        $pattern1 = { 85 C0 FE DD FF F9 A3 }  // TEST EAX followed by JE (not shown in examples)
        $pattern2 = { FE DD FF F9 A3 85 C0 ?? }  // Another variation with different offset
    condition:
        any of them
}