<?php

namespace BezhanSalleh\FilamentShield\Resources\RoleResource\Pages;

use BezhanSalleh\FilamentShield\Resources\RoleResource;
use BezhanSalleh\FilamentShield\Support\Utils;
use Filament\Actions;
use Filament\Resources\Pages\EditRecord;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;

class EditRole extends EditRecord {
    protected static string $resource = RoleResource::class;

    public Collection $permissions;

    protected function getActions(): array {
        return [
            Actions\DeleteAction::make(),
        ];
    }

    protected function mutateFormDataBeforeSave(array $data): array {
        $this->permissions = collect($data)
            ->except(['name', 'guard_name', 'select_all', Utils::getTenantModelForeignKey()])
            ->flatten()
            ->reject(fn($permission) => empty($permission) || $permission === '__rm__') // ✅ ignore removed
            ->unique()
            ->values();

        return Arr::only($data, ['name', 'guard_name', Utils::getTenantModelForeignKey()]);
    }

    protected function afterSave(): void {
        $roleName = $this->record->name;
        Log::info("Shield: Syncing permissions for role '{$roleName}'");

        // Get permissions currently assigned to this role
        $currentPermissionNames = $this->record->getPermissionNames()->all();

        // Normalise selected to plain strings
        $selected = $this->permissions->filter()->unique()->values()->all();

        // Find what was removed (currently has but not in selected)
        $toDetach = array_diff($currentPermissionNames, $selected);

        Log::info("Shield: Role '{$roleName}' - Selected permissions", [
            'count' => count($selected),
            'permissions' => $selected,
        ]);

        Log::info("Shield: Role '{$roleName}' - Currently assigned", [
            'count' => count($currentPermissionNames),
            'permissions' => $currentPermissionNames,
        ]);

        $permissionModel = Utils::getPermissionModel();

        // Ensure all selected permission models exist
        $permissionModels = $permissionModel::whereIn('name', $selected)->get();

        // Sync selected
        $this->record->syncPermissions($permissionModels);
        Log::info("Shield: Role '{$roleName}' - Synced " . count($permissionModels) . ' permissions');

        // Explicitly detach anything currently assigned but not in selected
        if (! empty($toDetach)) {
            $this->record->revokePermissionTo($toDetach);
            Log::info("Shield: Role '{$roleName}' - Revoked permissions", [
                'count' => count($toDetach),
                'permissions' => array_values($toDetach),
            ]);
        } else {
            Log::info("Shield: Role '{$roleName}' - No permissions to revoke");
        }

        $this->record->refresh();
        Log::info("Shield: Role '{$roleName}' - Sync complete");
    }
}
