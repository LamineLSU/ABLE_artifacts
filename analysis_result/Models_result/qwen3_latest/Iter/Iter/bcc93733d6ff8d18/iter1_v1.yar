rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 ?? ?? ?? ?? }  ; test eax, eax + je (0004617A-0004617C)
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? }  ; test eax, eax + je with large offset (00046188-0004618A)
        $pattern2 = { 85 C0 74 07 ?? ?? ?? ?? }  ; test eax, eax + short je (000461EC-000461EE)

    condition:
        any of them
}