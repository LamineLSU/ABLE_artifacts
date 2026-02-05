rule SandboxEvasion
{
    meta:
        author = "CyberSec Analyst"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        description = "Detects sandbox evasion techniques through specific API calls and memory checks"

    strings:
        $pattern0 = { 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? }
        $pattern1 = { 33 C0 E8 ?? ?? ?? ?? }
        $pattern2 = { E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? }

    condition:
        any of them
}