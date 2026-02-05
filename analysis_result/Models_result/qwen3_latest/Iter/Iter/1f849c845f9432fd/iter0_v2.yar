rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }  // Push ebx + call to sandbox check
        $pattern1 = { 50 E8 ?? ?? ?? ?? }      // Push eax + call to evasion check
        $pattern2 = { E8 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }  // Call to evasion logic + final exit call

    condition:
        any of them
}