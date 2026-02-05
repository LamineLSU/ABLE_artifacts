rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? 3C ?A ?D ?B } // Targeting a call instruction with an offset
        $pattern1 = { 75 0C 8A ?? ?? ?? } // Targeting a conditional jmp near
        $pattern2 = { 8B 45 ?? ?? 9E 0F } // Targeting a stack push with displacement

    condition:
        any of them
}