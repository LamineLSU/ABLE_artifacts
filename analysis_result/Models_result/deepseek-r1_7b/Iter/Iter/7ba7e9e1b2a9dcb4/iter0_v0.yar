rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting specific code paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 FF 8B EC FF 75 08 FF 00 96 00 00 } (Combines a test instruction and function call)
        $pattern1 = { E8 C8 FF FF FF CE FF 4A 3F FF 8C FF 00 12 FC } (Unique sequence for the second trace's bypass)
        $pattern2 = { 6A 5A FF FF 75 08 FF 75 08 5D E8 41 CA B0 41 } (Targeting lower address evasions)

    condition:
        any of them
}