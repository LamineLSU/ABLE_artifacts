rule Bypass_Sample
{
    meta:
        description = "Buffer Overflow Exploit"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 51 45 C3 68 A0 ?? ?? ?? 51 4D F8 A0 ?? ?? ?? }
        $pattern1 = { 4D 8C 7E 9E ?? ?? ?? 52 5C 51 1F ?? ?? ?? }
        $pattern2 = { 6A 53 B3 D7 ?? ?? ?? E8 C0 ?? ?? ?? }

    condition:
        any of them
}