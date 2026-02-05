rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific instructions targeting exit calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 20 }
        $pattern1 = { E8 C8 FF FF FF }  // Exact call to 0040E7C3h
        $pattern2 = { FF 15 AC B0 41 00 }  // Instruction before final call

    condition:
        any of them
}