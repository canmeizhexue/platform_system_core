/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cutils/multiuser.h>
#include <gtest/gtest.h>

TEST(MultiuserTest, TestMerge) {
    EXPECT_EQ(0, multiuser_get_uid(0, 0));
    EXPECT_EQ(1000, multiuser_get_uid(0, 1000));
    EXPECT_EQ(10000, multiuser_get_uid(0, 10000));
    EXPECT_EQ(50000, multiuser_get_uid(0, 50000));
    EXPECT_EQ(1000000, multiuser_get_uid(10, 0));
    EXPECT_EQ(1001000, multiuser_get_uid(10, 1000));
    EXPECT_EQ(1010000, multiuser_get_uid(10, 10000));
    EXPECT_EQ(1050000, multiuser_get_uid(10, 50000));
}

TEST(MultiuserTest, TestSplitUser) {
    EXPECT_EQ(0, multiuser_get_user_id(0));
    EXPECT_EQ(0, multiuser_get_user_id(1000));
    EXPECT_EQ(0, multiuser_get_user_id(10000));
    EXPECT_EQ(0, multiuser_get_user_id(50000));
    EXPECT_EQ(10, multiuser_get_user_id(1000000));
    EXPECT_EQ(10, multiuser_get_user_id(1001000));
    EXPECT_EQ(10, multiuser_get_user_id(1010000));
    EXPECT_EQ(10, multiuser_get_user_id(1050000));
}

TEST(MultiuserTest, TestSplitApp) {
    EXPECT_EQ(0, multiuser_get_app_id(0));
    EXPECT_EQ(1000, multiuser_get_app_id(1000));
    EXPECT_EQ(10000, multiuser_get_app_id(10000));
    EXPECT_EQ(50000, multiuser_get_app_id(50000));
    EXPECT_EQ(0, multiuser_get_app_id(1000000));
    EXPECT_EQ(1000, multiuser_get_app_id(1001000));
    EXPECT_EQ(10000, multiuser_get_app_id(1010000));
    EXPECT_EQ(50000, multiuser_get_app_id(1050000));
}

TEST(MultiuserTest, TestCache) {
    EXPECT_EQ(-1, multiuser_get_cache_gid(0, 0));
    EXPECT_EQ(-1, multiuser_get_cache_gid(0, 1000));
    EXPECT_EQ(20000, multiuser_get_cache_gid(0, 10000));
    EXPECT_EQ(-1, multiuser_get_cache_gid(0, 50000));
    EXPECT_EQ(1020000, multiuser_get_cache_gid(10, 10000));
}

TEST(MultiuserTest, TestExt) {
    EXPECT_EQ(-1, multiuser_get_ext_gid(0, 0));
    EXPECT_EQ(-1, multiuser_get_ext_gid(0, 1000));
    EXPECT_EQ(30000, multiuser_get_ext_gid(0, 10000));
    EXPECT_EQ(-1, multiuser_get_ext_gid(0, 50000));
    EXPECT_EQ(1030000, multiuser_get_ext_gid(10, 10000));
}

TEST(MultiuserTest, TestShared) {
    EXPECT_EQ(-1, multiuser_get_shared_gid(0, 0));
    EXPECT_EQ(-1, multiuser_get_shared_gid(0, 1000));
    EXPECT_EQ(50000, multiuser_get_shared_gid(0, 10000));
    EXPECT_EQ(-1, multiuser_get_shared_gid(0, 50000));
    EXPECT_EQ(1050000, multiuser_get_shared_gid(10, 10000));
}
