rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF C0 E8 C8 FF FF FF FF 15 AC B0 41 00 } // CALL instruction and subsequent conditional logic
        $pattern1 = { 83 F8 01 74 12 8B 4D F8 }  // API call related to exit decision
        $pattern2 = { 3D 00 10 00 00 0F 82 }  // Comparison instruction setting flags

    condition:
        any of them
}