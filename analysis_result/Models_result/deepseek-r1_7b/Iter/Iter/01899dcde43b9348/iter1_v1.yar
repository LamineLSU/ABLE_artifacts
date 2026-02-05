rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific instructions in memory"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? ?? E8 ?? }
        $pattern1 = { 6A ?? 5A 8B CE 85 C0 ??
                     8B EC 8D 40 53 9A 4F CA FF D1 F8 FF FE ??}
        $pattern2 = { 8B 45 E8 ?? ?? ?? ?? 8B 45 0F 84 ??? }

    condition:
        any of them
}