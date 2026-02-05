rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting conditional jumps and function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }  // Test and conditional jump (e.g., test eax, eax / jz)
        $pattern1 = { E8 ?? ?? ?? ?? 8B 45 ?? }  // Call followed by mov (e.g., call [address] / mov eax, [displacement])
        $pattern2 = { 50 E8 ?? ?? ?? ?? }         // Push followed by call (e.g., push eax / call [address])

    condition:
        any of them
}