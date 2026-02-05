rule Bypass_Push_call_B0ACh {
    meta:
        description = "Evasion by bypassing push dword ptr instruction to 0041B0ACh"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C8 00 FF 75 08 8B EC 55 61 20 }
        $pattern1 = { 55 61 20 E8 C8 FF 75 9B FF 75 }
        $pattern2 = { E8 C8 FF 75 08 8B EC 55 61 20 }

    condition:
        any of them
}