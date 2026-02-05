rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 6A 40 53 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }  // Push ebx, push 40h, push ebx, push addr, call
        $pattern1 = { 55 8B EC FF 75 08 E8 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }  // Push ebp, mov ebp, push dword, call
        $pattern2 = { 55 8B EC E8 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? ?? ?? ?? }  // Push ebp, mov ebp, call, push dword, call

    condition:
        any of them
}