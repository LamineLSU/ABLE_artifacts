rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with multiple specific patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC FF C3 5A B0 41 00 } // Call to 0040E7C3h followed by specific bytes
        $pattern1 = { E8 C8 FF FF FF 15 AC B0 41 00 } // Unconditional call to ExitProcess with offset
        $pattern2 = { FF 15 AC B0 41 00 } // Conditional bypass before exit decision

    condition:
        any of them
}