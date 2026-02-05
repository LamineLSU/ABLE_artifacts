rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? } // test+je
        $pattern2 = { E8 C8 FF FF FF FF 15 AC B0 41 00 } // call to exit function
        $pattern3 = { 83 F8 01 74 12 8B 4D F8 } // cmp+je

    condition:
        any of them
}