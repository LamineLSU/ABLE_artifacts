rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass patterns identified from trace analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 EC 40 E7 F3 FF C8 FF FF FF FF FF C8 FF FF FF FF FF }
        $pattern1 = { 8B EC 8D 43 01 8B EC E8 C8 FF FF FF 26 01 55 FF C8 FF FF FF FF FF }
        $pattern2 = { 8B E5 EB 03 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF }
}

    condition:
        any of them
}