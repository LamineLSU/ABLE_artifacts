rule Bypass_Sample {
    meta:
        description = "Evasion bypass patterns targeting stack manipulation and function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 75 08 E8 C8 FF FF }  // Push displacement followed by function call
        $pattern1 = { F8 75 08 E8 C8 FF FF }  // PUSHDW with displacement then function call
        $pattern2 = { 8B EC 05 E8 C8 FF FF }  // Push dword ptr [EC+05] followed by function call

    condition:
        any of them
}