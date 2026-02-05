rule BypassExitCall {
    meta:
        description = "Detects potential exit call sequences to bypass termination"
    condition:
        any of (
            ( 8BFF 55 8BEC FF7508 E8 ?? ?? ?? ?? ),
            ( FF7508 E8 ?? ?? ?? ?? 59 ),
            ( 59 FF15 ?? ?? ?? ?? FF7508 )
        )
}