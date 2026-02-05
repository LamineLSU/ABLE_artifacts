rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting multiple call sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = {
            8B EC FF75 08 E8 C8 FF FF FF FF 59 45
        }
        $pattern1 = {
            6A 40 53 B0 8D FC 5E 0F 84 ?? 45 25
        }
        $pattern2 = {
            FF75 08 E8C8FFFF 59 4B 0F 84 ?? ??
        }

    condition:
        any of them
}