rule Evasion_Bypass_Patterns {
    meta:
        description = "Evasion bypass detection using specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? ?? CA DD ?? } // TEST EAX followed by conditional call
        $pattern1 = { 74 07 ?? ?? CA DD ?? ?? } // JE condition check leading to call
        $pattern2 = { ?? ?? ?? ?? ?? DD ?? } // JZ bypass with offset manipulation

    condition:
        any of them
}