rule ControlFlowEvasion
{
    meta:
        description = "Detects potential control flow evasion or indirect function calls"
    
    strings:
        $call = /FF15 ?? ?? ?? ??/
        $test_jump = /85 C0 0F 84 ?? ?? ?? ??/
        $push_call = /6A ?? E8 ?? ?? ?? ??/
    
    condition:
        all of them
}