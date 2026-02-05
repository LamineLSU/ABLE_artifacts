rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting memory calls and conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 8B 45 74 12 6A 5B 5A 8B CE E8 C8 FF FF FF ?? }
        $pattern1 = { 00 1B A0 88 E8 C8 FF FF FF FF 15 AC B0 41 00 5A 74 12 ?? }
        $pattern2 = { 6A 5B 5A 8B CE E8 C8 FF FF FF FF 15 AC B0 41 00 ?? }

    condition:
        any of them
}