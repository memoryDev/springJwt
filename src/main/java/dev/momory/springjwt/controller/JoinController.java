package dev.momory.springjwt.controller;

import dev.momory.springjwt.dto.JoinDTO;
import dev.momory.springjwt.service.JoinService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Slf4j
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String joinProcess(JoinDTO joinDTO) {

        log.info("username = {}", joinDTO.getUsername());
        log.info("password = {}", joinDTO.getPassword());
        joinService.joinService(joinDTO);

        return "ok";

    }
}
