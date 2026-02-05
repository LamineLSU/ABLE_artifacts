rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - checked conditional logic and timing checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 8B EC ?? ?? ?? ?? 55 ?? }
        $pattern1 = { E8 ?? ?? ?? ?? FF C8 FF ?? ?? FF 75 08 E8 C8 FF FF FF FF 75 08 ?? ?? ?? ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 40 4F }

    condition:
        any of them
}