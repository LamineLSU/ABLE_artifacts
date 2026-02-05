rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting key execution paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 0F 8B C0 ?? ?? ?? ?? EAX ret 00h }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? TEST EAX,EAX }
        $pattern2 = { 8B C0 5A 8B CE E8 ?? ?? ?? ?? 74 0F }

    condition:
        any of them
}