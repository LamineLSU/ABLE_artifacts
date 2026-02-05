rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule with multiple call and jump patterns"

    strings:
        $pattern0 = { 85 C0 74 ?? }  // Test EAX and Jump
        $pattern1 = { FF 15 ?? ?? ?? ?? }  // Call instruction with offset
        $pattern2 = { 8B 45 ?? FF 15 ?? ?? ?? ?? }  // MOV + Call

    condition:
        any of them
}