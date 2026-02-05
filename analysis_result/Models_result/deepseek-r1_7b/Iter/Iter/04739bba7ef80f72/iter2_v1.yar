rule BypassSample {
    meta:
        description: "Evasion bypass rules targeting function calls and conditional jumps"
        cape_options: "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { B9 F8 26 43 E8 43 1C 00 }
        $pattern1 = { 74 0E E8 EE 82 FF }
        $pattern2 = { F3 F4 C9 }
}