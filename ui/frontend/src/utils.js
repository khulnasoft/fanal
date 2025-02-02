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

const crypto = require('crypto');

export const utils = {
  priorityToColor(priority) {
    switch (priority) {
      case 'Emergency':
        return '#C62828';
      case 'Alert':
        return '#D32F2F';
      case 'Critical':
        return '#E53935';
      case 'Error':
        return '#FF5252';
      case 'Warning':
        return '#FB8C00';
      case 'Notice':
        return '#1976D2';
      case 'Informational':
        return '#03A9F4';
      case 'Debug':
        return '#29B6F6';
      default:
        return '#555';
    }
  },
  stringToColor(str) {
    return `#${crypto.createHash('md5').update(str).digest('hex').substring(0, 6)}`;
  },
};

export default {
};
