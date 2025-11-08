<?php

namespace BezhanSalleh\FilamentShield\Resources\RoleResource\Pages;

use BezhanSalleh\FilamentShield\Resources\RoleResource;
use BezhanSalleh\FilamentShield\Support\Utils;
use Filament\Actions;
use Filament\Resources\Pages\EditRecord;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;

class EditRole extends EditRecord {
    protected static string $resource = RoleResource::class;

    public Collection $permissions;

    protected function getActions(): array {
        return [
            Actions\DeleteAction::make(),
        ];
    }

    protected function mutateFormDataBeforeSave(array $data): array {
        // Collect selected permissions from form data
        $this->permissions = collect($data)
            ->except(['name', 'guard_name', 'select_all', Utils::getTenantModelForeignKey()])
            ->flatten()
            ->filter() // just remove null/empty values
            ->unique();

        return Arr::only($data, ['name', 'guard_name', Utils::getTenantModelForeignKey()]);
    }

    protected function afterSave(): void {
        $permissionModel = Utils::getPermissionModel();
        $allPermissionNames = $permissionModel::pluck('name')->all();

        // Normalise to plain strings
        $selected = $this->permissions->filter()->unique()->values()->all();

        // Find what was removed
        $toDetach = array_diff($allPermissionNames, $selected);

        // Ensure all selected permission models exist
        $permissionModels = $permissionModel::whereIn('name', $selected)->get();

        // Sync selected
        $this->record->syncPermissions($permissionModels);

        // Explicitly detach anything not in selected
        if (! empty($toDetach)) {
            $this->record->revokePermissionTo($toDetach);
        }

        $this->record->refresh();
    }
}
