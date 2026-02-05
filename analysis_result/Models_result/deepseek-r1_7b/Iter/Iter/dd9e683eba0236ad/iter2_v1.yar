rule Bypass_Evasion_Bypass
{
    meta:
        description = "Evasion bypass using specific function calls and stack manipulations"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 10 ?? ?? ?? ?? ?? }  // Match any mov eax,dword
        $pattern1 = { 83 C4 14 ?? ?? ?? ?? ?? }  // Match any add esp,14h
        $pattern2 = { 8B 55 14 ?? ?? ?? ?? ?? }  // Match any mov edx,dword

    condition:
        (any of them)
}