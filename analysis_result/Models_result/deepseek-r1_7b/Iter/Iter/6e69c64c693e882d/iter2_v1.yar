rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - optimized based on previous traces"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC ?? ?? ?? ?? }  // After setup and before ExitProcess call
        $pattern1 = { E8 C8 FF FF FF 00 00 FF 75 08 ?? }  // Targeting the first call's arguments
        $pattern2 = { FF 15 AC B0 41 00 }  // Matching the second call's argument

    condition:
        any of them
}