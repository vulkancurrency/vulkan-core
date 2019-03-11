"""
// Copyright (c) 2019, The Vulkan Developers.
//
// This file is part of Vulkan.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// You should have received a copy of the MIT License
// along with Vulkan. If not, see <https://opensource.org/licenses/MIT>.
"""

import math


def get_block_reward(cumulative_emission):
    """
    Calculates the block reward based on the number of already emitted coins,
    until the supply reaches zero...
    """

    block_reward = (MAX_SUPPLY - cumulative_emission) >> EMISSION_FACTOR
    return block_reward


if __name__ == '__main__':
    DECIMALS = 8
    UNITS = int(math.pow(10, DECIMALS))
    MAX_SUPPLY = 64000000 * UNITS
    EMISSION_FACTOR = 18

    # get the block reward
    cumulative_emission = 0
    block_reward = get_block_reward(cumulative_emission)
    print ("Generated Coins", cumulative_emission, "Reward:", (block_reward / UNITS))
    cumulative_emission += block_reward
