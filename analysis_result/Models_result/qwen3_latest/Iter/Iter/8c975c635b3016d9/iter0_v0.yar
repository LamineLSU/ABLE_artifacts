rule Bypass_Sample
{
    meta:
        description = "Malware evasion pattern detection based on ExitProcess and related calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
    
    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }
        $pattern1 = { 8B CE E8 ?? ?? ?? ?? }
        $pattern2 = { 85 C0 74 12 6A 5B }
    
    condition:
        all of them
}