<?php

namespace {
    class CI_Input
    {
        /** @return array<string, string> */
        public function request_headers(): array {}

        public function method(bool $upper = false): string {}

        public function server(string $key): mixed {}

        public function get_request_header(string $name): ?string {}

        /** @return array<string, mixed> */
        public function get(): array {}

        public string $raw_input_stream;
    }

    class CI_URI
    {
        public function uri_string(): string {}
    }

    class CI_Router
    {
        public function fetch_class(): string {}

        public function fetch_method(): string {}
    }

    class CI_Controller
    {
        public CI_Input $input;
        public CI_URI $uri;
        public CI_Router $router;
    }
}

namespace LoGuard\Sdk\CodeIgniter3 {
    function &get_instance(): \CI_Controller {}
}
