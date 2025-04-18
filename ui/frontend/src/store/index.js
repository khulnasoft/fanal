// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The KhulnaSoft Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/* eslint-disable no-param-reassign */
import Vue from 'vue';
import Vuex from 'vuex';
import createPersistedState from 'vuex-persistedstate';

Vue.use(Vuex);

export default new Vuex.Store({
  plugins: [createPersistedState({
    storage: window.sessionStorage,
  })],
  state: {
    ticer: 0,
    refreshInterval: 10000,
    refreshIntervals: ['off', '10s', '20s', '30s', '1min', '2min'],
    username: '',
    password: '',
  },
  mutations: {
    increment(state) {
      state.ticer += 1;
    },
    setRefreshInterval(state, payload) {
      switch (payload) {
        case '10s':
          state.refreshInterval = 10000;
          break;
        case '20s':
          state.refreshInterval = 20000;
          break;
        case '30s':
          state.refreshInterval = 30000;
          break;
        case '1min':
          state.refreshInterval = 60000;
          break;
        case '2min':
          state.refreshInterval = 120000;
          break;
        case 'off':
          state.refreshInterval = 0;
          break;
        default:
          break;
      }
    },
    setCredentials(state, payload) {
      state.username = payload.username;
      state.password = payload.password;
    },
    emptyCredentials(state) {
      state.username = '';
      state.password = '';
    },
  },
  actions: {
    increment(context) {
      context.commit('increment');
    },
    setRefreshInterval(context, payload) {
      context.commit('setRefreshInterval', payload);
    },
    setCredentials(context, payload) {
      context.commit('setCredentials', payload);
    },
    emptyCredentials(context) {
      context.commit('emptyCredentials');
    },
  },
});
/* eslint-enable no-param-reassign */
