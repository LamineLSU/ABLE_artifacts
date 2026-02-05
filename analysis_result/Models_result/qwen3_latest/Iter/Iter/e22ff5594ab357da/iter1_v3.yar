rule MaliciousBehavior
{
    meta:
        description = "Detects evasion and termination behavior via API calls and control flow"
        cape_options = "bp0=$evade_check+0,action0=skip,bp1=$terminate_call+0,action1=skip,bp2=$exit_sequence+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2025-03-25"

    strings:
        $evade_check = { E8 ?? ?? ?? ?? 84 C0 74 ?? } (9)
        $terminate_call = { FF 15 ?? ?? ?? ?? } (6)
        $exit_sequence = { FF 75 08 FF 15 ?? ?? ?? ?? } (9)

    condition:
        any of ($evade_check, $terminate_call, $exit_sequence)
}