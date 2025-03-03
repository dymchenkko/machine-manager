# Copyright 2023 Cartesi Pte. Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use
# this file except in compliance with the License. You may obtain a copy of the
# License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

Feature: SessionGetProof feature

    Scenario Outline: asking for proofs with different parameters
        Given machine manager server is up
        And a machine manager server with a machine executed for <cycle> final cycles
        When the machine manager server asks machine for proof on cycle <cycle> for address <address> with log2_size <size>
        Then server returns correct proof

        Examples:
            | cycle |        address      | size |
            |  30   |          288        |  3   |
            |  30   |          288        |  4   |
