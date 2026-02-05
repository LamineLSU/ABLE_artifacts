rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting JZX and conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? 6A 5B } <!-- TEST EAX followed by JZX with displacement -->
        $pattern1 = { E8C8 FF75 ?? ... } <!-- JZX in trace #3 -->
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ... } <!-- Another bypass vector -->

    condition:
        any of them
}